package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.AdvancePayment;
import com.opethic.hrms.HRMSNew.models.master.EmployeeLeave;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.List;

public interface EmployeeLeaveRepository extends JpaRepository<EmployeeLeave, Long> {
    List<EmployeeLeave> findByEmployeeIdAndStatus(Long id, boolean b);

    EmployeeLeave findByIdAndStatus(Long leaveId, boolean b);

    EmployeeLeave findByEmployeeIdAndFromDateLessThanAndToDateGreaterThan(Long id, LocalDate localDate, LocalDate localDate1);

    EmployeeLeave findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqual(Long id, LocalDate localDate, LocalDate localDate1);

    List<EmployeeLeave> findByEmployeeIdAndStatusOrderByIdDesc(Long id, boolean b);

    EmployeeLeave findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqualAndLeaveStatus(Long id, LocalDate localDate, LocalDate localDate1, String approved);

    @Query(value = "SELECT * FROM `employee_leave_tbl` WHERE ?1 BETWEEN from_date AND to_date AND leave_status='Approved'", nativeQuery = true)
    List<EmployeeLeave> getEmployeesOnLeave(String now);

    @Query(value = "SELECT * FROM `employee_leave_tbl` WHERE leave_status='Pending' AND employee_id IN(SELECT id from employee_tbl WHERE status = 1)", nativeQuery = true)
    List<EmployeeLeave> getPendingLeaveRequests();

    @Query(value = "SELECT hrms_new_db.emp_leave.* FROM hrms_new_db.employee_leave_tbl emp_leave LEFT JOIN hrms_new_db.employee_tbl emp " +
            "ON emp_leave.employee_id = emp.id WHERE YEAR(emp_leave.applied_on)=?1 AND MONTH(emp_leave.applied_on)=?2 AND " +
            "emp_leave.status=1 AND emp.company_id = ?3 AND emp.branch_id = ?4", nativeQuery = true)
    List<EmployeeLeave> getEmplLeaveRequestsOfMonth(String year, String month, Long companyId, Long branchId);

    @Query(value = "SELECT * FROM employee_leave_tbl emp_leave LEFT JOIN employee_tbl emp ON " +
            "emp_leave.employee_id = emp.id WHERE emp_leave.leave_status=?1 AND emp.shift_id=?2 AND ?3 between from_date " +
            "AND to_date AND emp.company_id=?4 AND emp.branch_id=?5", nativeQuery = true)
    List<EmployeeLeave> getListByShiftAndStatus(String status, Long shiftId, String date, Long companyId, Long branchId);

    @Query(value = "SELECT * FROM hrms_new_db.employee_leave_tbl WHERE YEAR(applied_on)=?1 AND MONTH(applied_on)=?2 AND employee_id=?3 AND status=1", nativeQuery = true)
    List<EmployeeLeave> getEmplLeaveStatus(String year, String month, Long empId);
}
