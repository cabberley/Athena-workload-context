from athena_context.api.cohort_composition import (
    create_cohort_application,
)
from athena_context.api.cohort_production import (
    create_production_cohort_services,
)

app = create_cohort_application(create_production_cohort_services())

__all__ = ["app"]
