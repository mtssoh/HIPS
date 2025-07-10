install:
	sudo pip install -r requirements.txt

backend:
	sudo uvicorn app.main:app --reload

frontend:
	cd web && python3 -m http.server 8001

run:
	(make frontend & make backend & wait)

