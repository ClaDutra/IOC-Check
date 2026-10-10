from flask import request


def json_body():
    return request.get_json(silent=True) or {}


def page_args(default_per_page=20, max_per_page=100):
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = request.args.get("per_page", default_per_page, type=int)
    return page, min(max(per_page, 1), max_per_page)


def paginated(query, serializer=None):
    page, per_page = page_args()
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    serializer = serializer or (lambda item: item.to_dict())
    return {
        "items": [serializer(item) for item in pagination.items],
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
        "total": pagination.total,
    }
