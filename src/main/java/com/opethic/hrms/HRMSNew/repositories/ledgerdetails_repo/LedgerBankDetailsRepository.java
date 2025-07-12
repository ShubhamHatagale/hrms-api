package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.master.LedgerBankDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LedgerBankDetailsRepository extends JpaRepository<LedgerBankDetails,Long> {
    List<LedgerBankDetails> findByLedgerMasterIdAndStatus(Long id, boolean b);

    LedgerBankDetails findByIdAndStatus(long id, boolean b);
}
