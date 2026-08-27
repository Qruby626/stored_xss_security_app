"""Application entry point.

Hanya digunakan untuk lingkungan pengembangan dan penelitian localhost.
Untuk produksi, gunakan WSGI server seperti gunicorn atau uWSGI.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # host tidak disetel ke 0.0.0.0 karena aplikasi ini
    # hanya digunakan di lingkungan localhost untuk penelitian.
    app.run(debug=True)
