import unittest

from services.route_permissions import get_employee_route_permission


class EmployeeRoutePermissionTests(unittest.TestCase):

    def test_department_routes(self):
        self.assertEqual(
            get_employee_route_permission("company_departments", "GET"),
            ("hr", "view"),
        )
        self.assertEqual(
            get_employee_route_permission("company_departments", "POST"),
            ("hr", "create"),
        )
        self.assertEqual(
            get_employee_route_permission("update_company_department", "PATCH"),
            ("hr", "manage"),
        )

    def test_branch_routes(self):
        self.assertEqual(
            get_employee_route_permission("company_branches", "GET"),
            ("hr", "view"),
        )
        self.assertEqual(
            get_employee_route_permission("company_branches", "POST"),
            ("hr", "create"),
        )
        self.assertEqual(
            get_employee_route_permission("update_company_branch", "PATCH"),
            ("hr", "manage"),
        )

    def test_staff_routes(self):
        self.assertEqual(
            get_employee_route_permission("add_staff", "POST"),
            ("hr", "create"),
        )
        self.assertEqual(
            get_employee_route_permission("list_staff", "GET"),
            ("hr", "view"),
        )
        self.assertEqual(
            get_employee_route_permission("set_staff_active", "PATCH"),
            ("hr", "manage"),
        )
        self.assertEqual(
            get_employee_route_permission(
                "set_employee_lifecycle_status", "PATCH"
            ),
            ("hr", "manage"),
        )
        self.assertEqual(
            get_employee_route_permission(
                "employee_lifecycle_history", "GET"
            ),
            ("hr", "view"),
        )

    def test_attendance_routes(self):
        self.assertEqual(
            get_employee_route_permission("att", "GET"),
            ("hr", "view"),
        )
        self.assertEqual(
            get_employee_route_permission("correct_attendance", "POST"),
            ("hr", "update"),
        )
        self.assertEqual(
            get_employee_route_permission("attendance_audit", "GET"),
            ("hr", "view"),
        )
        self.assertEqual(
            get_employee_route_permission("stats", "GET"),
            ("hr", "view"),
        )

    def test_unmapped_routes_are_denied(self):
        for endpoint, method in [
            ("settings_route", "GET"),
            ("settings_route", "POST"),
            ("subscribe", "POST"),
            ("subs", "GET"),
            ("company_lifecycle_status", "GET"),
            ("approve_sub", "POST"),
            ("unknown_route", "GET"),
            ("att", "POST"),
        ]:
            with self.subTest(endpoint=endpoint, method=method):
                self.assertIsNone(
                    get_employee_route_permission(endpoint, method)
                )

    def test_endpoint_and_method_matching_is_exact(self):
        self.assertIsNone(
            get_employee_route_permission("company_departments_extra", "GET")
        )
        self.assertIsNone(
            get_employee_route_permission("company_departments", "DELETE")
        )

    def test_method_is_case_normalized(self):
        self.assertEqual(
            get_employee_route_permission("att", "get"),
            ("hr", "view"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
