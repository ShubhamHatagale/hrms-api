package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Payhead;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PayheadRepository extends JpaRepository<Payhead, Long> {
    Payhead findByIdAndStatus(Long payheadId, boolean b);

    List<Payhead> findByStatus(boolean b);

    @Query(value = "SELECT * FROM `payhead_tbl` WHERE status=1", nativeQuery = true)
    List<Payhead> findAllBystatus();

    @Query(value = "SELECT * FROM `payhead_tbl` WHERE is_default=1", nativeQuery = true)
    List<Payhead> getDefaultPayheads();

    @Query(value = "SELECT * FROM hrms_new_db.payhead_tbl WHERE is_default =0 OR is_default IS NULL", nativeQuery = true)
    List<Payhead> getPayheadsList();

    List<Payhead> findByCompanyIdAndStatus(Long id, boolean b);

    List<Payhead> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);

    List<Payhead> findByIsDefaultAndStatus(boolean b, boolean b1);
}
