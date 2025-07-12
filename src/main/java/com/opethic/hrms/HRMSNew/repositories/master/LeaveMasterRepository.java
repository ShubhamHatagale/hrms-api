package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.LeaveMaster;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface LeaveMasterRepository extends JpaRepository<LeaveMaster, Long> {
    LeaveMaster findByIdAndStatus(long id, boolean b);

    List<LeaveMaster> findByStatus(boolean b);
    @Query(value = "SELECT t1.name, t1.id, t1.leaves_allowed, IFNULL(t2.usedleaves,0) AS usedleaves FROM leave_master_tbl t1 " +
            "LEFT JOIN (SELECT leave_master_id, SUM(total_days) AS usedleaves FROM `employee_leave_tbl` WHERE employee_id=?1  AND leave_status='Approved' GROUP BY " +
            "leave_master_id) AS t2 ON t1.id = t2.leave_master_id WHERE  t1.company_id=?2 AND t1.branch_id=?3", nativeQuery = true)
    List<Object[]> getEmployeeLeavesDashboardData(Long employeeId, Long cid, Long bid);

    @Query(value = "SELECT IFNULL(SUM(total_days), 0) AS total_leaves FROM `employee_leave_tbl` WHERE employee_id=?1 AND leave_type_id=?2 AND leave_status='Approved'", nativeQuery = true)
    Long getLeavesAlreadyApplied(Long id, Long categoryId);

    List<LeaveMaster> findByCompanyIdAndStatus(Long id, boolean b);

    List<LeaveMaster> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
}
