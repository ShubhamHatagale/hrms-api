package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Attendance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.List;

public interface AttendanceRepository extends JpaRepository<Attendance, Long> {
    Attendance findByEmployeeIdAndAttendanceDateAndStatus(Long id, LocalDate now, boolean b);

    Attendance findByIdAndStatus(Long attendanceId, boolean b);

    @Query(value = "SELECT * FROM attendance_tbl WHERE employee_id=?1 AND status =?2 AND check_out_time IS NULL ORDER BY id DESC" +
            " LIMIT 1",
            nativeQuery = true)
    Attendance findLastRecordOfEmployeeWithoutCheckOut(Long id, boolean b);

    @Query(value = "SELECT * FROM attendance_tbl WHERE employee_id=?1 AND attendance_date!=?2 AND check_out_time IS " +
            "NOT NULL ORDER BY id DESC LIMIT 1",
            nativeQuery = true)
    Attendance findLastSecondRecordOfEmployee(Long id, LocalDate localDate);

    @Query(value = "SELECT IFNULL(COUNT(att.id),0.0) FROM attendance_tbl att LEFT JOIN employee_tbl emp ON att.employee_id=emp.id " +
            "WHERE emp.status=1 AND att.attendance_date=?1 AND emp.company_id=?2 AND att.is_half_day IS NULL",
            nativeQuery = true)
    Double getPresentEmployeeCount(LocalDate b, Long companyId);
    @Query(value = "SELECT IFNULL(COUNT(DISTINCT(employee_id)),0) FROM `employee_leave_tbl` LEFT JOIN employee_tbl ON" +
            " employee_leave_tbl.employee_id=employee_tbl.id  WHERE leave_status='Approved' AND from_date<=?1 AND" +
            " to_date>=?1 AND employee_leave_tbl.employee_id NOT IN (SELECT attendance_tbl.employee_id from" +
            " attendance_tbl WHERE attendance_date=?1 AND employee_tbl.company_id=?2)",
            nativeQuery = true)
    int getLeaveEmployeeCount(LocalDate localDate, Long companyId);
    @Query(value = "SELECT IFNULL(COUNT(attendance_tbl.id),0) FROM `attendance_tbl` WHERE attendance_date=?1 AND is_half_day=1", nativeQuery = true)
    int getHalfDayEmployeeCount(LocalDate date);

    @Query(value = "SELECT * FROM attendance_tbl att LEFT JOIN employee_tbl emp ON att.employee_id=emp.id WHERE emp.status=1 AND att.attendance_date=?1", nativeQuery = true)
    List<Attendance> getPresentEmployees(String now);
    @Query(value = "SELECT * FROM `attendance_tbl` WHERE employee_id=?3 AND MONTH(attendance_date) = ?2 AND YEAR(attendance_date) = ?1", nativeQuery = true)
    List<Attendance> getAttendanceOfEmployee(String year, String month, Long employeeId);
    @Query(value = "SELECT SUM(overtime) AS overtime FROM `attendance_tbl` WHERE employee_id=?1 AND" +
            " MONTH(attendance_date)=?3 AND YEAR(attendance_date)=?2  AND is_attendance_approved=1", nativeQuery = true)
    Long getOvertimeCount(Long id, String userYear, String userMonth);
    @Query(value = "SELECT SUM(overtime_amount) AS amount FROM `attendance_tbl` WHERE employee_id=?1 AND" +
            " MONTH(attendance_date)=?3 AND YEAR(attendance_date)=?2   AND is_attendance_approved=1", nativeQuery = true)
    Double getOvertimeAmount(Long id, String userYear, String userMonth);

    @Query(value = "SELECT IFNULL(COUNT(attendance_tbl.id),0) FROM `attendance_tbl` WHERE company_id=?1 AND attendance_date=?2",
            nativeQuery = true)
    int getPresentEmployeeCountOfCompany(Long id, LocalDate todayDate);
    @Query(value = "SELECT COUNT(id) FROM `attendance_tbl` WHERE YEAR(attendance_date)=?1 AND MONTH(attendance_date)=?2" +
            " AND employee_id=?3 AND status=?4 AND attendance_status=?5", nativeQuery = true)
    double getPresentDaysOfEmployeeOfMonth(int year, int month, Long employeeId, boolean b, String approve);

    @Query(value = "SELECT * FROM `attendance_tbl` WHERE YEAR(attendance_date)=?1 AND MONTH(attendance_date)=?2 AND" +
            " employee_id=?3 AND status=?4 AND attendance_status=?5", nativeQuery = true)
    List<Attendance> getAttendanceListOfEmployee(int year, int month, Long employeeId, boolean b, String approve);
    @Query(value = "SELECT COUNT(is_late) AS late_count FROM `attendance_tbl` WHERE employee_id=?1 AND is_late=1 AND MONTH(attendance_date)=?2", nativeQuery = true)
    Long getLateCount(Long id, String monthValue);

    @Query(value = "SELECT * from attendance_tbl WHERE status=1 AND YEAR(attendance_date)=?1 AND MONTH(attendance_date)=?2 AND (is_manual_punch_in=1 OR is_manual_punch_out=1)", nativeQuery = true)
    List<Attendance> getManualAttendanceListOfAll(String year, String month);
    @Query(value = "SELECT * from attendance_tbl WHERE status=1 AND employee_id=?1 AND YEAR(attendance_date)=?2 AND MONTH(attendance_date)=?3 AND (is_manual_punch_in=1 OR is_manual_punch_out=1)", nativeQuery = true)
    List<Attendance> getManualAttendanceList(Long employeeId, String year, String month);

    @Query(value = "SELECT * FROM attendance_tbl att LEFT JOIN employee_tbl emp ON att.employee_id=emp.id WHERE emp.status=1 " +
            "AND att.attendance_date=?1 AND emp.shift_id=?2 AND emp.company_id=?3 AND emp.branch_id=?4", nativeQuery = true)
    List<Attendance> getPresentEmployeesByDateAndSite(String now, Long shiftId, Long id, Long id1);

    List<Attendance> findByCheckOutTimeIsNull();
    List<Attendance> findAllByAttendanceDateAndStatus(LocalDate today, boolean b);

    @Query(value = "SELECT att.* FROM hrms_new_db.attendance_tbl att LEFT JOIN hrms_new_db.employee_tbl emp ON att.employee_id=emp.id " +
            "where att.attendance_date=?1 AND att.check_out_time IS NULL AND att.shift_id=?2 AND emp.company_id=?3 AND emp.site_id=?4", nativeQuery = true)
    List<Attendance> getPunchInData(String date, Long shiftId, Long cid, Long bid);

    @Query(value = "SELECT att.* FROM hrms_new_db.attendance_tbl att LEFT JOIN hrms_new_db.employee_tbl emp ON att.employee_id=emp.id " +
            "where att.attendance_date=?1 AND att.check_out_time IS NOT NULL AND att.shift_id=?2 AND emp.company_id=?3 AND emp.site_id=?4", nativeQuery = true)
    List<Attendance> getPunchOutData(String date, Long shiftId, Long cid, Long bid);

    @Query(value = "SELECT att.* FROM hrms_new_db.attendance_tbl att LEFT JOIN hrms_new_db.employee_tbl emp ON att.employee_id=emp.id where " +
            "att.attendance_date=?1 AND att.check_out_time IS NOT NULL AND emp.company_id=?2", nativeQuery = true)
    List<Attendance> getPunchInListWithoutBranch(String date, Long id);
}
