import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.settings import dollar_settings
from src.api import router


app = FastAPI(
    title="Billing Service For Companies And Customers",
    description="Register one account to pay for all online services.",
    version="1.0.1"
)

app.include_router(router)

allow_origins = ["*"]  # 'http://localhost:8080', 'http://127.0.0.1:8080'

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


if __name__ == "__main__":
    uvicorn.run(
        "src.dollar:app",
        host=dollar_settings.server_host,
        port=dollar_settings.server_port,
        reload=True
    )


"""
from outside of 'src' directory run: python3 -m src.dollar
"""