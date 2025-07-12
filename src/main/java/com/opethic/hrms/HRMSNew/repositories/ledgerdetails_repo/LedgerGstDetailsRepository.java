package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.master.LedgerGstDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LedgerGstDetailsRepository extends JpaRepository<LedgerGstDetails,Long> {
    List<LedgerGstDetails> findByLedgerMasterIdAndStatus(Long ledgerId, boolean b);

    LedgerGstDetails findByIdAndStatus(long id, boolean b);
}
