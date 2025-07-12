package com.opethic.hrms.HRMSNew.repositories.tranx_repository.gstinput_repository;

import com.opethic.hrms.HRMSNew.models.tranx.gstinput.GstInputDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface GstInputDetailsRepository extends JpaRepository<GstInputDetails,Long> {
    List<GstInputDetails> findByGstInputMasterIdAndStatus(Long id, boolean b);

    GstInputDetails findByIdAndStatus(Long details_id, boolean b);
}
