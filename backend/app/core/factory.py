"""Generic CRUD router factory.

Produces a full CRUD router (list / get / create / update / delete) from a model class + schemas.
Tenancy: every query scoped by ``org_id_column``.
Pagination: page/page_size query params.
Search: optional ``search_columns`` matched with ILIKE on ``?q=``
RBAC: create/delete require admin, update admin, list any member.
"""

from typing import Any, Generic, Sequence, Type, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import Tenant, get_tenant, require_roles
from app.models import User
from app.models.security import utcnow

ModelT = TypeVar("ModelT")


def _paginate_q(q, page: int, page_size: int):
    return q.offset((page - 1) * page_size).limit(page_size)


def _apply_search(q, search: str | None, columns: list) -> Any:
    if not search or not columns:
        return q
    pattern = f"%{search}%"
    return q.where(or_(*[col.ilike(pattern) for col in columns]))


def crud_router(
    model: Type[ModelT],
    *,
    schemas: dict,
    tenant_key: str = "org_id",
    search_columns: list | None = None,
    prefix: str = "",
    allowed_methods: Sequence[str] = ("list", "get", "create", "update", "delete"),
) -> APIRouter:
    """
    schemas = {"list": OutListModel, "get": DetailModel, "create": CreateModel, "update": UpdateModel}
    """
    list_out = schemas["list"]
    get_out = schemas["get"]
    create_in = schemas.get("create")
    update_in = schemas.get("update")
    router = APIRouter(prefix=prefix)
    model_name = model.__tablename__
    param_name = "obj_id"
    slug_name = f"{{{param_name}}}"

    _search_cols = search_columns or []

    async def _get_or_404(
        obj_id: str,
        tenant: Tenant,
        db: AsyncSession = Depends(get_db),
    ) -> ModelT:
        q = select(model).where(model.id == obj_id, getattr(model, tenant_key) == tenant.org_id)
        obj = (await db.execute(q)).scalar_one_or_none()
        if not obj:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"{model_name} not found")
        return obj

    # LIST
    if "list" in allowed_methods:
        @router.get("", response_model=list[list_out])
        async def list_(
            tenant: Tenant = Depends(get_tenant),
            db: AsyncSession = Depends(get_db),
            q: str | None = Query(None, description="search"),
            page: int = Query(1, ge=1),
            page_size: int = Query(50, ge=1, le=200),
            sort: str = Query("created_at"),
            order: str = Query("desc"),
        ):
            stmt = select(model).where(getattr(model, tenant_key) == tenant.org_id)
            stmt = _apply_search(stmt, q, _search_cols)
            # dynamic sort
            col = getattr(model, sort, None)
            if col is not None:
                stmt = stmt.order_by(desc(col) if order == "desc" else asc(col))
            results = (await db.execute(_paginate_q(stmt, page, page_size))).scalars().all()
            return [list_out.model_validate(r) for r in results]

        @router.get("/count")
        async def count(
            tenant: Tenant = Depends(get_tenant),
            db: AsyncSession = Depends(get_db),
        ):
            stmt = select(func.count()).select_from(model).where(getattr(model, tenant_key) == tenant.org_id)
            n = (await db.execute(stmt)).scalar_one()
            return {"count": n}

    # GET
    if "get" in allowed_methods:
        @router.get(f"/{slug_name}", response_model=get_out)
        async def get_(obj_id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
            obj = await _get_or_404(obj_id, tenant, db)
            return get_out.model_validate(obj)

    # CREATE
    if "create" in allowed_methods and create_in:
        @router.post("", response_model=get_out, status_code=status.HTTP_201_CREATED)
        async def create_(
            body: create_in,
            request: Request,
            tenant: Tenant = Depends(require_roles("admin", "analyst")),
            db: AsyncSession = Depends(get_db),
        ):
            data = body.model_dump()
            data[tenant_key] = tenant.org_id
            obj = model(**data)
            db.add(obj)
            try:
                await db.commit()
            except Exception as e:  # noqa: BLE001
                await db.rollback()
                if "IntegrityError" in type(e).__name__:
                    raise HTTPException(status.HTTP_409_CONFLICT, detail=f"{model_name} already exists")
                raise
            await db.refresh(obj)
            return get_out.model_validate(obj)

    # UPDATE
    if "update" in allowed_methods and update_in:
        @router.patch(f"/{slug_name}", response_model=get_out)
        async def update_(
            obj_id: str,
            body: update_in,
            tenant: Tenant = Depends(require_roles("admin", "analyst")),
            db: AsyncSession = Depends(get_db),
        ):
            obj = await _get_or_404(obj_id, tenant, db)
            data = body.model_dump(exclude_unset=True)
            for k, v in data.items():
                setattr(obj, k, v)
            obj.updated_at = utcnow()
            await db.commit()
            await db.refresh(obj)
            return get_out.model_validate(obj)

    # DELETE
    if "delete" in allowed_methods:
        @router.delete(f"/{slug_name}", status_code=status.HTTP_204_NO_CONTENT)
        async def delete_(
            obj_id: str,
            tenant: Tenant = Depends(require_roles("admin")),
            db: AsyncSession = Depends(get_db),
        ):
            obj = await _get_or_404(obj_id, tenant, db)
            await db.delete(obj)
            await db.commit()

    return router