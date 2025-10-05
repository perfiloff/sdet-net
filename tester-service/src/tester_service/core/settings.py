
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    project_name: str = Field("movies", alias="PROJECT_NAME")
    debug: bool = Field(False, alias="DEBUG")