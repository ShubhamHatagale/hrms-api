package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.master.LedgerBillingDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LedgerBillingDetailsRepository extends JpaRepository<LedgerBillingDetails,Long> {
    List<LedgerBillingDetails> findByLedgerMasterIdAndStatus(Long ledgerId, boolean b);

    LedgerBillingDetails findByIdAndStatus(long id, boolean b);
}
