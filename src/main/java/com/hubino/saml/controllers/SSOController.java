package com.hubino.saml.controllers;

import com.fasterxml.jackson.databind.util.JSONPObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Set;

@Controller
@RequestMapping("/saml")
public class SSOController {

    // Logger
    private static final Logger LOG = LoggerFactory.getLogger(SSOController.class);

    @Autowired
    private MetadataManager metadata;

    @GetMapping("/discovery")
    @CrossOrigin
    public ResponseEntity<Object> idpSelection(HttpServletRequest request, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null)
            LOG.debug("Current authentication instance from security context is null");
        else
            LOG.debug("Current authentication instance from security context: {}", this.getClass().getSimpleName());
        HashMap<String, Object> responseMap = new HashMap<>();
        if (auth == null || (auth instanceof AnonymousAuthenticationToken)) {
            Set<String> idps = metadata.getIDPEntityNames();
            for (String idp : idps)
                LOG.info("Configured Identity Provider for SSO: {}", idp);
            model.addAttribute("idps", idps);
            responseMap.put("idps", idps);
            responseMap.put("message", "DISCOVERY_SUCCESS");
            responseMap.put("redirect", "pages/discovery");
            System.out.println(responseMap);
        } else {
            LOG.warn("The current user is already logged.");
            responseMap.put("idps", null);
            responseMap.put("message", "USER_ALREADY_LOGGED");
            responseMap.put("redirect", "redirect:/landing");
        }
        return new ResponseEntity<>(responseMap, HttpStatus.OK);
    }

}
