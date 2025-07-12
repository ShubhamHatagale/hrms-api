package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Foundations;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FoundationRepository extends JpaRepository<Foundations,Long> {

    Foundations findByIdAndStatus(Long foundationId, boolean b);
}
