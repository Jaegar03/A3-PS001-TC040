# Local Evaluation Environment

Recorded on 2026-10-11 (Asia/Calcutta) for branch `audit/ml-hardening`.

## Host

| Property | Value |
|---|---|
| OS | Windows 11 Home Single Language, 10.0.26200 |
| CPU | AMD Ryzen 5 5600H with Radeon Graphics |
| Physical cores / logical processors | 6 / 12 |
| Visible RAM | 15,708 MiB (~15.0 GiB) |
| Free RAM at capture | 2,420 MiB (~2.3 GiB) |
| GPU | AMD Radeon RX 6500M (4 GiB) and integrated AMD Radeon Graphics |
| CUDA / MPS | Not available on this Windows/AMD setup; experiments default to CPU |
| D: volume | 146.5 GiB total; 74.7 GiB free |
| Python | 3.14.2 |
| Repository HEAD at capture | `cb84e869d48a5c3012a34e212e9a368d489c0575` |

## Research environment

The clean audit environment is `backend/.venv-audit/`, created with:

```powershell
python -m venv backend\.venv-audit
backend\.venv-audit\Scripts\python -m pip install -e "backend[dev]"
```

Selected installed versions can be printed with:

```powershell
backend\.venv-audit\Scripts\python -c "import fastapi,lightgbm,numpy,onnxruntime,pydantic,sklearn,sqlalchemy,yara; print(f'fastapi={fastapi.__version__}'); print(f'lightgbm={lightgbm.__version__}'); print(f'numpy={numpy.__version__}'); print(f'onnxruntime={onnxruntime.__version__}'); print(f'pydantic={pydantic.__version__}'); print(f'scikit-learn={sklearn.__version__}'); print(f'sqlalchemy={sqlalchemy.__version__}'); print(f'yara={yara.__version__}')"
```

At baseline capture, the installed research/runtime environment included FastAPI 0.143.0, LightGBM 4.7.0, NumPy 2.5.4, ONNX Runtime 1.31.0, ONNX 1.23.2, skl2onnx 1.20.0, Pydantic 2.14.0, scikit-learn 1.9.1, SQLAlchemy 2.1.4, and yara-python 4.5.4. The environment is CPU-feasible for the existing rule and classical-ML work. The low free-RAM observation is a constraint: large transformer training and full public network datasets must be downloaded and processed only after a measured memory plan.

Telemetry-disabled environment variables used for local research commands:

```powershell
$env:WANDB_DISABLED="true"
$env:HF_HUB_DISABLE_TELEMETRY="1"
$env:OTEL_SDK_DISABLED="true"
```

No GPU acceleration was assumed. No data or metrics were uploaded.
