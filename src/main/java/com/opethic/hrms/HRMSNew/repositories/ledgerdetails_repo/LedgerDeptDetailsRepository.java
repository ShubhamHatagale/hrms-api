package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.master.LedgerDeptDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LedgerDeptDetailsRepository extends JpaRepository<LedgerDeptDetails,Long> {
    List<LedgerDeptDetails> findByLedgerMasterIdAndStatus(Long ledgerId, boolean b);

    LedgerDeptDetails findByIdAndStatus(long id, boolean b);
}
