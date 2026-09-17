from sqlalchemy import inspect


def model_to_dict(obj) -> dict:
    if obj is None:
        return None
    return {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}
