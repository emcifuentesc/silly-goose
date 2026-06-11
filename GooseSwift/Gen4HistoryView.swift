import Darwin
import Foundation
import SwiftUI
import UIKit

struct Gen4HistoryView: View {
  @ObservedObject var store: HealthDataStore

  var body: some View {
    ScrollView {
      LazyVStack(alignment: .leading, spacing: 14) {
        statusHeader

        if !store.gen4HistoryRecords.isEmpty {
          heartRateSection
        }
      }
      .padding(.horizontal, 16)
      .padding(.vertical, 18)
    }
    .gooseScreenBackground()
    .navigationTitle("Gen4 HR History")
    .navigationBarTitleDisplayMode(.inline)
    .toolbarBackground(.hidden, for: .navigationBar)
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        Button { store.refreshGen4History() } label: {
          Image(systemName: "arrow.clockwise")
        }
        .accessibilityLabel("Refresh Gen4 history")
      }
    }
    .onAppear {
      store.refreshGen4History()
    }
  }

  private var statusHeader: some View {
    HStack(spacing: 10) {
      Image(systemName: "waveform.path.ecg.rectangle")
        .font(.system(size: 16, weight: .semibold))
        .foregroundStyle(.red)
        .frame(width: 30, height: 30)
        .background(Color.red.opacity(0.14), in: Circle())
      VStack(alignment: .leading, spacing: 2) {
        Text("WHOOP 4.0 Heart Rate")
          .font(.headline.weight(.semibold))
        Text(store.gen4HistoryStatus)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .minimumScaleFactor(0.74)
      }
      Spacer()
    }
    .padding(16)
    .healthDashboardSurface(tint: .red, tintOpacity: 0.05)
  }

  private var heartRateSection: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text("Recent Heart Rate")
        .font(.subheadline.weight(.semibold))
        .foregroundStyle(.secondary)
        .padding(.bottom, 2)

      ForEach(recentSamples.indices, id: \.self) { i in
        Gen4HrSampleRow(record: recentSamples[i])
      }
    }
    .padding(16)
    .healthDashboardSurface(tint: .red, tintOpacity: 0.03)
  }

  private var recentSamples: [[String: Any]] {
    Array(store.gen4HistoryRecords.suffix(200).reversed())
  }
}

private struct Gen4HrSampleRow: View {
  let record: [String: Any]

  var body: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text(timestampText)
          .font(.caption.monospacedDigit())
          .foregroundStyle(.secondary)
        if let rr = rrText {
          Text(rr)
            .font(.caption2)
            .foregroundStyle(.tertiary)
        }
      }
      Spacer()
      if let bpm = (record["heart_rate"] as? NSNumber)?.intValue {
        HStack(alignment: .firstTextBaseline, spacing: 3) {
          Text("\(bpm)")
            .font(.system(.body, design: .rounded).weight(.semibold).monospacedDigit())
            .foregroundStyle(.red)
          Text("bpm")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      } else {
        Text("--")
          .font(.body.monospacedDigit())
          .foregroundStyle(.secondary)
      }
    }
    .padding(.vertical, 4)
    Divider()
  }

  private var timestampText: String {
    guard let ts = (record["ts"] as? NSNumber)?.int64Value else { return "?" }
    let date = Date(timeIntervalSince1970: TimeInterval(ts))
    return date.formatted(.dateTime.month().day().hour().minute().second())
  }

  private var rrText: String? {
    guard let raw = record["rr_intervals_ms"] as? [Any], !raw.isEmpty else { return nil }
    let rrs = raw.compactMap { ($0 as? NSNumber)?.intValue }
    guard !rrs.isEmpty else { return nil }
    let avg = rrs.reduce(0, +) / rrs.count
    return "RR avg \(avg) ms · \(rrs.count) beats"
  }
}
