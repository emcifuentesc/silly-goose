import CoreBluetooth
import Foundation
import OSLog


extension GooseBLEClient {
  func beginHistoricalSync(
    trigger: String,
    automatic: Bool,
    firstCommandOverride: HistoricalCommandKind? = nil,
    rangeOnly: Bool = false,
    acknowledgeHistoricalDataResult: Bool = true
  ) {
    guard !isHistoricalSyncing else {
      record(level: .debug, source: "ble.sync", title: "historical_sync.skipped", body: "already syncing trigger=\(trigger)")
      return
    }
    guard activePeripheral != nil, commandCharacteristic != nil else {
      failHistoricalSync("Historical sync needs an active WHOOP command characteristic. Current connection state: \(connectionState).")
      return
    }
    guard connectionState == "ready" else {
      failHistoricalSync("Historical sync can only start from the ready state. Current connection state: \(connectionState).")
      return
    }
    guard supportsV5HistoricalSync else {
      let characteristic = commandCharacteristic?.uuid.uuidString ?? "missing"
      failHistoricalSync("Historical sync currently supports the Goose V5 fd4b command characteristic. Active command characteristic: \(characteristic).")
      return
    }

    historicalSyncRunID = UUID()
    historicalRangePollOnly = rangeOnly
    historicalDataResultAckEnabled = acknowledgeHistoricalDataResult
    isHistoricalSyncing = true
    historicalSyncStatus = "syncing"
    historicalPacketCount = 0
    historicalPacketsReceivedThisSync = 0
    lastHistoricalPacketCountPublishedAt = Date.distantPast
    lastHistoricalSyncProgressCallbackAt = Date.distantPast
    lastHistoricalSyncProgressCallbackStatus = ""
    lastHistoricalSyncProgressCallbackDetail = ""
    coalescedHistoricalSyncProgressCallbackCount = 0
    historyEndAckQueued = false
    historyEndAckSentThisBurst = false
    pendingHistoryEndAckPayload = nil
    historyEndReceived = false
    historyCompleteReceived = false
    historyStartReceived = false
    historicalRangePendingResponses = 0
    historicalRangeRetryCount = 0
    historicalTransferRequestAttemptCount = 0
    pendingHistoricalCommand = nil
    historicalCommandTimeoutWorkItem?.cancel()
    historicalIdleWorkItem?.cancel()
    historicalRangeRetryWorkItem?.cancel()
    let toastDetail = rangeOnly
      ? "Polling historical range"
      : (automatic ? "Requesting missed packets" : "Requesting historical packets")
    publishSyncToast(phase: .syncing, detail: toastDetail)
    // WHOOP 4.0 does not return the v5 paged "final range" response, so the range-poll just times
    // out and fails the sync. Gen4 (like my-whoop) drives the offload straight from
    // SEND_HISTORICAL_DATA → HISTORY_START/data/END; the range poll is a v5-only precursor.
    let useRangePoll = requestHistoricalRangeBeforeTransfer && activeDeviceGeneration == .gen5
    var firstCommand = firstCommandOverride ?? (useRangePoll ? .getDataRange : .sendHistoricalData)
    // Several callers pass `firstCommandOverride: .getDataRange` (rangeFirst). On Gen4 that hangs,
    // so for any real transfer (not an explicit range-only poll) lead with SEND_HISTORICAL_DATA.
    if activeDeviceGeneration == .gen4, firstCommand == .getDataRange, !rangeOnly {
      firstCommand = .sendHistoricalData
    }
    if firstCommand == .getDataRange {
      updateHistoricalRangeDebugStatus("started trigger=\(trigger) first=GET_DATA_RANGE")
    }
    record(
      source: "ble.sync",
      title: "historical_sync.started",
      body: "trigger=\(trigger) first=\(firstCommand.name) range_only=\(rangeOnly) ack_enabled=\(historicalDataResultAckEnabled)"
    )
    notifyHistoricalSyncProgress(status: "syncing", detail: "Starting \(firstCommand.name)", terminal: false, failed: false)
    writeHistoricalCommand(firstCommand)
  }

  func writeHistoricalCommand(_ kind: HistoricalCommandKind) {
    guard isHistoricalSyncing else {
      return
    }
    guard let activePeripheral, let commandCharacteristic else {
      failHistoricalSync("Lost the command characteristic before writing \(kind.name).")
      return
    }
    guard let writeType = writeType(for: commandCharacteristic) else {
      failHistoricalSync("Command characteristic \(commandCharacteristic.uuid.uuidString) is not writable for \(kind.name).")
      return
    }

    let commandPayload: [UInt8]
    if kind == .historicalDataResult {
      commandPayload = pendingHistoryEndAckPayload ?? kind.payload
    } else if kind == .sendHistoricalData, activeDeviceGeneration == .gen4 {
      // WHOOP 4.0 expects a single zero byte for SEND_HISTORICAL_DATA (v5 sends an empty payload).
      // EnterHighFreqSync (cmd 96) is intentionally NOT sent here: noop verified that plain
      // SEND_HISTORICAL_DATA [0x00] serves type-47 normally (50 records), while entering high-freq
      // mode first produces 0 records. ExitHighFreqSync is sent in the Gen4 handshake to release any
      // strap left parked in high-freq by a previous session.
      commandPayload = [0x00]
    } else {
      commandPayload = kind.payload
    }
    let sequence = nextHistoricalSequence()
    let frame = buildCommandFrame(
      sequence: sequence,
      command: kind.commandNumber,
      data: commandPayload
    )
    if kind == .sendHistoricalData {
      historicalTransferRequestAttemptCount += 1
    }
    if kind == .historicalDataResult {
      pendingHistoricalCommand = nil
      historicalCommandTimeoutWorkItem?.cancel()
    } else {
      pendingHistoricalCommand = PendingHistoricalCommand(kind: kind, sequence: sequence)
      scheduleHistoricalCommandTimeout(kind: kind, sequence: sequence)
    }
    activePeripheral.writeValue(frame, for: commandCharacteristic, type: writeType)
    emitCommandWrite(
      source: "ble.sync",
      commandName: kind.name,
      commandNumber: kind.commandNumber,
      sequence: sequence,
      payload: Data(commandPayload),
      frame: frame,
      peripheral: activePeripheral,
      characteristic: commandCharacteristic,
      writeType: writeType
    )
    if kind == .getDataRange {
      updateHistoricalRangeDebugStatus("sent seq=\(sequence) \(writeTypeName(writeType)) frame=\(frame.hexString)")
    }
    notifyHistoricalSyncProgress(status: "syncing", detail: "Sent \(kind.name) seq \(sequence)", terminal: false, failed: false)
    record(
      source: "ble.sync",
      title: "historical_sync.command.sent",
      body: "\(kind.name) seq=\(sequence) \(writeTypeName(writeType)) payload=\(Data(commandPayload).hexString) \(frame.hexString)"
    )
    if kind == .historicalDataResult {
      record(
        source: "ble.sync",
        title: "historical_sync.result_ack.sent",
        body: "seq=\(sequence) payload=\(Data(commandPayload).hexString) fire_and_forget=true"
      )
      if historyCompleteReceived {
        completeHistoricalSync(reason: "history_result_ack_sent_after_complete")
      } else {
        scheduleHistoricalIdleCompletion(reason: "history_result_ack_sent")
      }
    }
  }

  func nextHistoricalSequence() -> UInt8 {
    let sequence = nextHistoricalCommandSequence
    nextHistoricalCommandSequence = nextHistoricalCommandSequence == UInt8.max ? 57 : nextHistoricalCommandSequence + 1
    return sequence
  }

  func writeType(for characteristic: CBCharacteristic) -> CBCharacteristicWriteType? {
    if characteristic.properties.contains(.write) {
      return .withResponse
    }
    if characteristic.properties.contains(.writeWithoutResponse) {
      return .withoutResponse
    }
    return nil
  }

  func debugCommandPayload(
    for definition: GooseDebugCommandDefinition,
    payloadHex: String?
  ) -> [UInt8]? {
    if definition.id == "get_device_config_value" || definition.id == "get_feature_flag_value" {
      guard let data = Self.normalizedHexData(payloadHex) else {
        return nil
      }
      if data.count == 32 {
        return [1] + Array(data)
      }
      if data.count == 33 {
        return Array(data)
      }
      return nil
    }

    if definition.requiresPayloadHex {
      guard let data = Self.normalizedHexData(payloadHex), !data.isEmpty else {
        return nil
      }
      return Array(data)
    }

    let defaultHex = payloadHex ?? definition.defaultPayloadHex ?? ""
    guard let data = Self.normalizedHexData(defaultHex) else {
      return nil
    }
    return Array(data)
  }

  static func normalizedHexData(_ hex: String?) -> Data? {
    let normalized = (hex ?? "").filter { !$0.isWhitespace }
    guard normalized.count.isMultiple(of: 2) else {
      return nil
    }

    var data = Data()
    var index = normalized.startIndex
    while index < normalized.endIndex {
      let nextIndex = normalized.index(index, offsetBy: 2)
      guard let byte = UInt8(normalized[index..<nextIndex], radix: 16) else {
        return nil
      }
      data.append(byte)
      index = nextIndex
    }
    return data
  }

}
