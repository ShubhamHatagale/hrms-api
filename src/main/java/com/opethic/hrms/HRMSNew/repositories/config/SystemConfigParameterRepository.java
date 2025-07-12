package com.opethic.hrms.HRMSNew.repositories.config;

import com.opethic.hrms.HRMSNew.config.SystemConfigParameter;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SystemConfigParameterRepository extends JpaRepository<SystemConfigParameter,Long> {
    List<SystemConfigParameter> findByStatus(boolean b);

    SystemConfigParameter findByIdAndStatus(Long id, boolean b);
}
