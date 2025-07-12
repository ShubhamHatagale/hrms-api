package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.master.LedgerShippingAddress;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LedgerShippingDetailsRepository extends JpaRepository<LedgerShippingAddress,Long> {
    List<LedgerShippingAddress> findByLedgerMasterIdAndStatus(Long ledgerId, boolean b);

    LedgerShippingAddress findByIdAndStatus(Long id, boolean b);
}
