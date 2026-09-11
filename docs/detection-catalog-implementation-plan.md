# Detection Catalog Implementation Plan

## Existing components reused

- React Router routes, the existing dark design tokens in `frontend/src/styles.css`, Rule Explorer table, Rule Inspector, current `/api/rules` pagination/filtering, and existing classification/provenance serializers.
- SQLAlchemy `Rule`, `Classification`, and manual-review history; no parser or classifier semantics were changed.

## Dependency decision

The frontend currently uses React, React Router, Vite and TypeScript only. No new UI dependency was added. TanStack Table is not required for the current server-paginated table; TanStack Query would be useful in a later request-cancellation/cache refactor but is not being introduced while the existing request layer works. shadcn/ui would require adding a competing Tailwind/Radix stack. Motion and Recharts do not solve a current catalog requirement. Lucide React is optional, but the existing UI has only a small icon vocabulary and adding it now would not materially improve the core workflow.

## Implemented slice

- `/catalog`, `/catalog/rules`, `/catalog/candidates`, and `/catalog/mitre` entry routes (existing Explorer is reused).
- Server-side catalog stats, facets, candidates and UTF-8 CSV export endpoints.
- URL-persisted search/category/subcategory/MITRE/product filters and full filtered server export.
- Rule-level Product Planning statuses, notes and history, intentionally separate from Manual Review.
- Product Planning controls in Rule Inspector.

## Deliberately deferred

The existing catalog still needs a dedicated MITRE hierarchy page, progressive facet counts that recalculate against every active filter, bulk product actions, related-rule panels, metadata-quality overview and automated browser tests. These should be added as separate slices rather than replacing working components or introducing a second design system.
