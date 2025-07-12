package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Break;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;

public interface BreakRepository extends JpaRepository<Break, Long> {
    Break findByIdAndStatus(Long taskId, boolean b);

    @Query(
            value = " SELECT IFNULL(SUM(hours_worked),0) FROM break_tbl as a WHERE a.attendance_id=?1",
            nativeQuery = true
    )
    double getSumOfActualWorkTime(Long id);

    @Query(value = "SELECT IFNULL(SUM(total_break_time),0) FROM `break_tbl` WHERE attendance_id=?1", nativeQuery = true)
    double getSumOfBreakTime(Long id);
    
    @Query(value = "SELECT break_start_time FROM `task_master_tbl` WHERE attendance_id=?1 AND status=1 ORDER BY start_time ASC LIMIT 1", nativeQuery = true)
    LocalDateTime getInTime(Long id);

    //    @Query(value = "SELECT end_time FROM `task_master_tbl` WHERE attendance_id=?1 AND work_done=1 AND status=1 ORDER BY end_time DESC LIMIT 1", nativeQuery = true)
    @Query(value = "SELECT break_end_time FROM `task_master_tbl` WHERE attendance_id=?1 AND status=1 ORDER BY end_time DESC LIMIT 1", nativeQuery = true)
    LocalDateTime getOutTime(Long id);

    List<Break> findByAttendanceIdAndStatus(Long id, boolean b);

    Break findTop1ByAttendanceIdAndStatusAndBreakStatus(Long attendanceId, boolean b, String s);

    @Query(value = "SELECT * FROM hrms_new_db.break_tbl where attendance_id = ?1 AND status = ?2 ORDER BY id DESC", nativeQuery = true)
    List<Break> getBreakData(Long id, boolean b);

    @Query(value = "SELECT SUM(total_break_time) FROM hrms_new_db.break_tbl where attendance_id=?1 AND status = 1", nativeQuery = true)
    Double getBreakSummary(Long id);

    List<Break> findByAttendanceIdAndStatusAndBreakEndTimeIsNull(Long id, boolean b);
}
