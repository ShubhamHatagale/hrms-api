package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.BalancingMethod;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BalancingMethodRepository extends JpaRepository<BalancingMethod,Long> {
    BalancingMethod findByIdAndStatus(long balancing_method, boolean b);
}
