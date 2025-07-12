package com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo;

import com.opethic.hrms.HRMSNew.models.master.LedgerFormParameter;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LedgerFormRepository extends JpaRepository<LedgerFormParameter,Long> {
    LedgerFormParameter findByFormName(String others);
}
