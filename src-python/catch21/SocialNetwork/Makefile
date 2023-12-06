venv:
	apt-get install -y python3-venv
	python3 -m venv venv
	venv/bin/pip install -r requirements.lock

lint:
	python3 -m flake8 app.py
	python3 -m pylint app.py