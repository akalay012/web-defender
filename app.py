from webdefender.engine import app
from webdefender.application import start_optional_workers

start_optional_workers()

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","5000")),
            debug=os.getenv("FLASK_DEBUG","0").lower() in ("1","true","yes","on"))
