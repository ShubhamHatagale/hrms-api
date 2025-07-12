package com.opethic.hrms.HRMSNew.repositories.config;

import com.opethic.hrms.HRMSNew.config.AppConfig;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AppConfigRepository extends JpaRepository<AppConfig, Long> {
    AppConfig findByIdAndStatus(long id, boolean b);

    List<AppConfig> findByCompanyIdAndStatusAndBranchId(Long companyId, boolean b, Long id);

    List<AppConfig> findByCompanyIdAndStatusAndBranchIsNull(Long companyId, boolean b);

    List<AppConfig> findByCompanyIdAndStatus(Long id, boolean b);
}
