package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.TaxMaster;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface TaxMasterRepository extends JpaRepository<TaxMaster, Long> {

    TaxMaster findByIdAndStatus(long id, boolean b);

    List<TaxMaster> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);

    @Query(
            value = " SELECT * FROM tax_master_tbl WHERE company_id=?1 AND branch_id=?2 AND gst_per=?3 AND status=?4", nativeQuery = true
    )
    TaxMaster findDuplicateGSTWithBranch(Long outletId, Long branchId, String gst_per, boolean b);

    @Query(
            value = " SELECT * FROM tax_master_tbl WHERE company_id=?1 AND gst_per=?2 AND status=?3 AND branch_id IS NULL", nativeQuery = true
    )
    TaxMaster findDuplicateGSTWithCompany(Long id, String gst_per,boolean b);

    List<TaxMaster> findByCompanyIdAndStatusAndBranchIsNull(Long id, boolean b);
}
