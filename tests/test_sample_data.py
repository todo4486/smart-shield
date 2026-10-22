from __future__ import annotations

from scripts import make_sample_data
from services import dataset_service, telemetry_service
from services.telemetry_service import TelemetryImportOptions


def test_sample_files_are_labelled_reproducible_and_importable(tmp_path, analyst):
    make_sample_data.main(["--out", str(tmp_path / "a")])
    make_sample_data.main(["--out", str(tmp_path / "b")])
    files = sorted(p.name for p in (tmp_path / "a").glob("*.csv"))
    assert files and all(name.startswith("SAMPLE_") and name.endswith("_synthetic.csv") for name in files)
    for name in files:  # fixed seeds -> byte-identical output
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()

    telemetry = (tmp_path / "a" / "SAMPLE_telemetry_7days_synthetic.csv").read_bytes()
    report = telemetry_service.import_telemetry_csv(analyst, telemetry, "SAMPLE_telemetry_7days_synthetic.csv",
                                                    TelemetryImportOptions(source_name="SAMPLE (synthetic)"))
    assert report.rows_rejected == 0 and sorted(report.interfaces) == ["campus-uplink", "lab-link"]

    errors = (tmp_path / "a" / "SAMPLE_telemetry_with_errors_synthetic.csv").read_bytes()
    report = telemetry_service.import_telemetry_csv(analyst, errors, "errors.csv",
                                                    TelemetryImportOptions(source_name="SAMPLE errors (synthetic)"))
    assert report.rows_rejected == 6 and report.duplicate_rows == 1

    train = (tmp_path / "a" / "SAMPLE_intrusion_train_day_synthetic.csv").read_bytes()
    dataset = dataset_service.register_intrusion_dataset(analyst, train, "train.csv", "SAMPLE train (synthetic)")
    assert set(dataset.label_distribution) == {"BENIGN", "DDoS", "DoS Hulk", "PortScan", "FTP-Patator"}
    assert dataset.infinite_values


def test_committed_samples_match_the_generator(tmp_path):
    make_sample_data.main(["--out", str(tmp_path)])
    for path in tmp_path.glob("*.csv"):
        committed = make_sample_data.SAMPLES_DIR / path.name
        assert committed.exists(), f"Run python -m scripts.make_sample_data ({path.name} missing)"
        assert committed.read_bytes() == path.read_bytes(), f"{path.name} is stale; regenerate the samples"
