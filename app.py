from secureauth import create_app

# App entry point used by `python app.py` during local development.
app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
