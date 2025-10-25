from fastapi import FastAPI
from enum import Enum
from typing import Optional

app = FastAPI()

@app.get("/")
async def read_root():
    return {"Hello": "World"}

@app.get("/users/me")
async def read_user_me():
    return {"user_id": "the current user"}  


@app.get("/users/{user_id}")
async def read_user(user_id: str):
    return {"user_id": user_id}


    
class ModelName(str, Enum):
    alexnet = "alexnet"
    resnet = "resnet"
    lenet = "lenet"     
    
    
@app.get("/models/{model_name}")
async def get_model(model_name: ModelName):
    if model_name == ModelName.alexnet:
        return {"model_name": model_name, "message": "Deep Learning FTW!"}
    if model_name.value == 'resnet':
        return {"model_name": model_name, "message": "LeCNN all the images"}
    return {"model_name": model_name, "message": "Have some residuals"}


fake_items_db = {"foo": "The Foo Wrestlers", "bar": "The Bar Fighters", "baz": "The Baz Crusaders"}

@app.get("/items/")
async def read_item(skip: int = 0, limit: int = 2):
    items = list(fake_items_db.items())
    return items[skip : skip + limit]

@app.get("/items/{item_id}")
async def read_item(item_id: str, q: Optional[str] = None, short: bool = False):
    item = {"item_id": item_id}
    if q:
        item.update({"q": q})
    if not short:
        item.update(
            {
                "description": "This is an amazing item that has a long description"
            }
        )
    return item

@app.get("/users/{user_id}/items/{item_id}")
async def read_user_item(user_id:int,item_id: str,q: Optional[str]=None,short:bool=False):
    item= {'item_id':item_id,'owner_id':user_id}
    if q:
        item.update({'q':q})
    if not short:
        item.update(
            {
                "description": "This is an amazing item that has a long description"
            }
        )
    return item

@app.get("/items/required/{item_id}")
async def read_required_user_item(item_id:str,needy:str):
    item={'item_id':item_id,'needy':needy}
    
    return item