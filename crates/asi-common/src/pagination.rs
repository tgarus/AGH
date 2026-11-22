use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams, ToSchema)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<SortDir>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitizedPagination {
    pub page: u32,
    pub per_page: u32,
    pub offset: u64,
}

impl PaginationQuery {
    pub const DEFAULT_PER_PAGE: u32 = 50;
    pub const MAX_PER_PAGE: u32 = 200;

    #[must_use]
    pub fn sanitized(&self) -> SanitizedPagination {
        let page = self.page.unwrap_or(1).max(1);
        let per_page = self
            .per_page
            .unwrap_or(Self::DEFAULT_PER_PAGE)
            .clamp(1, Self::MAX_PER_PAGE);
        let offset = u64::from(page - 1) * u64::from(per_page);
        SanitizedPagination {
            page,
            per_page,
            offset,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PaginationMeta {
    pub page: u32,
    pub per_page: u32,
    pub total_items: u64,
    pub total_pages: u32,
}

impl PaginationMeta {
    #[must_use]
    pub fn new(page: u32, per_page: u32, total_items: u64) -> Self {
        let per_page_u64 = u64::from(per_page.max(1));
        let total_pages = if total_items == 0 {
            0
        } else {
            let pages = total_items.div_ceil(per_page_u64);
            u32::try_from(pages).unwrap_or(u32::MAX)
        };
        Self {
            page,
            per_page,
            total_items,
            total_pages,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: PaginationMeta,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_clamps_bounds() {
        let q = PaginationQuery {
            page: Some(0),
            per_page: Some(999),
            ..Default::default()
        };
        let s = q.sanitized();
        assert_eq!(s.page, 1);
        assert_eq!(s.per_page, 200);
        assert_eq!(s.offset, 0);

        let q2 = PaginationQuery {
            page: Some(3),
            per_page: Some(25),
            ..Default::default()
        };
        assert_eq!(q2.sanitized().offset, 50);
    }

    #[test]
    fn pagination_meta_calculates_pages() {
        let meta = PaginationMeta::new(1, 50, 101);
        assert_eq!(meta.total_pages, 3);
        assert_eq!(PaginationMeta::new(1, 50, 0).total_pages, 0);
    }
}
