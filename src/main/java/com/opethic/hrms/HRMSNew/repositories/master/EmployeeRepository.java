package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.List;

public interface EmployeeRepository extends JpaRepository<Employee,Long> {
    Employee findByMobileNumber(Long mobileNumber);

    List<Employee> findByCompanyIdAndStatusOrderByFirstNameAsc(Long id, boolean b);
    @Query(value = " SELECT IFNULL(COUNT(id),0.0) FROM employee_tbl as a WHERE a.status=?1 AND company_id=?2", nativeQuery = true)
    Double getEmployeeCount(boolean b, Long companyId);
    @Query(value = "SELECT IFNULL(COUNT(att.id),0.0) FROM attendance_tbl att LEFT JOIN employee_tbl emp ON att.employee_id=emp.id " +
            "WHERE emp.status=1 AND att.attendance_date=?1 AND att.company_id=?2 AND att.is_half_day IS NULL",
            nativeQuery = true)
    Double getPresentEmployeeCount(LocalDate b, Long companyId);

    Employee findByIdAndStatus(Long employeeId, boolean b);

    List<Employee> findByCompanyIdAndStatus(Long id, boolean b);

    @Query(value = "SELECT * FROM employee_tbl emp LEFT JOIN `employee_leave_tbl` emp_leave ON emp.id = emp_leave.employee_id WHERE ?1 BETWEEN emp_leave.from_date AND emp_leave.to_date AND emp_leave.leave_status='Approved'", nativeQuery = true)
    List<Employee> getEmployeesOnLeave(String now);

    @Query(value = " SELECT IFNULL(COUNT(id),0) FROM employee_tbl as a WHERE a.company_id=?1 AND a.status=?2", nativeQuery = true)
    int getEmployeeCountOfCompany(Long id, boolean b);

    List<Employee> findByStatus(boolean b);

    @Query(value = "SELECT IFNULL(expected_salary, 0) FROM employee_tbl  WHERE employee_id=?1 AND effected_date<=?2" +
            " ORDER BY effected_date DESC LIMIT 1", nativeQuery = true)
    Double getEmployeeSalary(Long employeeId, LocalDate now);

    Employee findByMobileNumberAndTextPassword(String username, String password);

    Employee findByCompanyIdAndMobileNumber(Long id, long parseLong);

    List<Employee> findByCompanyIdOrderByFirstName(Long id);

    Employee findByIdAndCompanyIdAndStatus(Long employeeId, Long id, boolean b);

    Employee findByMobileNumberAndStatus(long parseLong, boolean b);
    List<Employee> findByCompanyIdAndShiftIdAndStatus(Long id, Long id1, boolean b);
    @Query(value = "SELECT * FROM hrms_new_db.employee_tbl emp LEFT JOIN hrms_new_db.employee_leave_tbl emp_leave ON " +
            "emp.id = emp_leave.employee_id WHERE ?1 BETWEEN emp_leave.from_date AND emp_leave.to_date AND " +
            "emp_leave.leave_status='Approved' AND emp.shift_id=?2 AND emp.company_id=?3 AND emp.branch_id=?4", nativeQuery = true)
    List<Employee> getEmployeeLeaveDataForDashboard(String now, Long shiftId, Long cid, Long bid);

    List<Employee> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
    List<Employee> findByCompanyIdAndBranchIdAndShiftIdAndStatus(Long id, Long id1, Long id2, boolean b);
}
