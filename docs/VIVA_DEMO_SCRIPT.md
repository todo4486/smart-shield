# Viva demo script (about 2 minutes)

Uses replay mode, so it needs no live network and gives the same result every time.

## Before the viva (5 minutes, once)

1. `streamlit run app.py`, sign in as the admin.
2. **ML Laboratory → Data sources → Register intrusion dataset:** register
   `samples/SAMPLE_intrusion_train_day_synthetic.csv` and `samples/SAMPLE_intrusion_attack_during_peak_synthetic.csv`.
3. **ML Laboratory:** train Smart Shield models on the train-day file and tick *Activate*.
4. Optional, for the PredictNet part: import `samples/SAMPLE_telemetry_7days_synthetic.csv`, train a forecaster on
   `campus-uplink` and activate it (see `samples/README.md`).
5. If you rehearsed, **Replay / demo → Clear replay data** so the demo starts clean.
6. Open the **Replay / demo** page and leave it there. Keep the browser window wide.

## The two minutes

| Time | Do | Say |
| --- | --- | --- |
| 0:00 | Point at the header strip. | "This is the SOC view. Every page has the health ring, live counters and a source badge. Nothing here is invented: if data is missing it says *unavailable*." |
| 0:10 | Pick the *attack during peak* dataset, **Port scan → DDoS**, **30×**, then **Start replay**. | "I'm replaying a labelled dataset through the real, hash-verified models. It is marked DATASET REPLAY everywhere and stored apart from real data." |
| 0:25 | Open **Network Map**. | "Hosts and links from the flows as they arrive. Thickness is throughput, rings show the worst alert, and moving dots are busy links. The victim host lights up as the DDoS starts." |
| 0:45 | Wait for the toast, then open **Incident Center**. | "Alerts from both engines are grouped on one timeline. The badges map each attack type to MITRE ATT&CK, for example Discovery T1046 for the port scan and Impact T1498 for the flood." |
| 1:00 | Click **Acknowledge**, then assign it to yourself. | "Triage is role-checked on the server and every step goes into the audit log." |
| 1:10 | **Smart Shield Security → Alerts**, pick the DDoS alert, turn on **Why was this flagged?** | "A plain explanation: the model's own feature importances, how far this traffic is from normal traffic, and the anomaly score against its threshold. The score is uncalibrated, so it is never called a probability." |
| 1:30 | **What-if simulator**: drag one demand slider up. | "PredictNet's bandwidth allocator, in a sandbox. Same water-filling function as real recommendations: minimums first, then share by weight, and unmet demand is reported. It never touches the network; enforcement is a separate, admin-only, confirmed and reversible step." |
| 1:45 | **Reports → Incident report → Build**, then show the download. | "One click gives a printable report: timeline, hosts, ATT&CK, explanations, actions from the audit log and notes." |
| 1:55 | Back to **Replay / demo** → **Stop**. | "And because it was a replay, an admin can clear it in one audited step." |

## Threat mitigation (about 3 minutes more)

Needs a registered live-compatible model: **ML Laboratory**, feature set *live-compatible*. It does not have to be the active one.
Leave the policy on **Recommend**. Everything here is simulated and labelled so, and no packet is sent.

| Time | Do | Say |
| --- | --- | --- |
| 0:00 | **Simulation → Bandwidth hog**, capacity 100 Mbit/s, then **Start simulation**. | "This creates traffic records in memory. They go through the real flow extractor and the real Random Forest, so no verdict is scripted." |
| 0:30 | **Bandwidth Management → Live network**: tiles, allocation graph, host table. | "One host is taking most of the link. The models flagged it, and that is what starts things. A busy link alone never does, because congestion is not an attack." |
| 0:50 | **Incident Center**: open the incident, read the evidence, enter a reason and click **Approve**. | "Status is Mitigation pending. Confidence, severity, repetition and false-positive risk are kept separate. None is a probability. By default an administrator decides." |
| 1:20 | **Bandwidth Management → Attack response**. Wait about 10 seconds for the after picture. | "Before and after come from stored samples. The hog goes down to its limit, legitimate traffic gets its share back, and loss falls. It says Simulated because it is." |
| 1:50 | **Incident Center → Roll back**. | "Every action expires and is reversible in one click. The audit log records all of it." |
| 2:10 | **Bandwidth Management → Forecast**: source `historical import`, interface `campus-uplink`, **Forecast now**. | "PredictNet predicts 5 and 10 minutes ahead and recommends acting early. With no validated model it says unavailable, and it never changes a real link by itself." |
| 2:40 | **Enforcement (advanced)**. | "On a real network this runs pf or tc. It is in dry run here, showing the exact commands. I have not run it in a real kernel, because that needs root." |

If asked about a flood: run **DDoS-like flood**. Recovery shows **Partly recovered**, because a controller on your side cannot free a
link that is already full. Mitigation has to happen upstream, and the app says so.

See `docs/ACCEPTANCE.md` for what was checked where. Rehearse with the Mac on power and the lid open: real-time simulation stalls if
it sleeps.

## If something goes wrong

- **No toast?** Toasts only show incidents that are new since the page opened. Open the Incident Center directly.
- **Clicking a host on the map does nothing:** use the *Or pick a host* list under the map.
- **Replay stopped by itself:** this happens if a source file was edited while the server ran. Press **Play it again**.
- **Questions on honesty:** the sample data is synthetic and labelled as such; replay keeps the dataset's own
  timestamps; the drift check and reports only read stored data.
