from fastapi import FastAPI, Depends
from db import get_db, require_user

app = FastAPI()


@app.get("/items/{item_id}")
def read_item(item_id: int, user=Depends(require_user)):
    return get_db().execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()


@app.get("/mine/{item_id}")
def read_mine(item_id: int, user=Depends(require_user)):
    return get_db().execute("SELECT * FROM items WHERE id = ? AND owner_id = ?", (item_id, user.id)).fetchone()
