from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardPagination(PageNumberPagination):
    """
    {count, page, page_size, results}. An out-of-range page is clamped to the last page instead of
    returning 404, so a stale bookmark or a shrinking result set never produces an error screen.
    """

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

    def paginate_queryset(self, queryset, request, view=None):
        page_size = self.get_page_size(request)
        paginator = self.django_paginator_class(queryset, page_size)
        try:
            number = int(request.query_params.get(self.page_query_param, 1))
        except (TypeError, ValueError):
            number = 1
        number = min(max(number, 1), paginator.num_pages)
        self.page = paginator.page(number)
        self.request = request
        return list(self.page)

    def get_paginated_response(self, data):
        return Response(
            {
                "count": self.page.paginator.count,
                "page": self.page.number,
                "page_size": self.page.paginator.per_page,
                "results": data,
            }
        )
