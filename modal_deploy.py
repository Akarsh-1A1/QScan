import modal

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("nmap")
    .pip_install_from_requirements("requirements.txt")
    .pip_install_from_requirements("qscan_backend/requirements.txt")
    .add_local_dir(".", "/app", copy=True,
        ignore=[
            "**/__pycache__",
            "**/*.pyc",
            "**/*.pyo",
            "venv/**",
            ".venv/**",
            ".git/**",
            ".env",
            "*.log",
            "results/**",
            "output/**",
            "qscan_frontend/**",
            "Run Snapshots/**",
            "Crypto Bill/**",
            "*.db",
            "*.sqlite3",
            "ai_ml/nist_cache.json",
        ]
    )
)

app = modal.App("qscan", image=image)

@app.function(
    secrets=[modal.Secret.from_name("qscan-secrets")],
    timeout=300,
)
@modal.asgi_app()
def fastapi_app():
    import sys
    sys.path.insert(0, "/app")
    sys.path.insert(0, "/app/qscan_backend")
    from main import app as fastapi_application
    return fastapi_application