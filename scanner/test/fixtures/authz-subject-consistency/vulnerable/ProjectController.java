package com.example.projects;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class ProjectController {

  private final ProjectService projectService;
  private final PermissionValidator permissionValidator;

  public ProjectController(ProjectService projectService, PermissionValidator permissionValidator) {
    this.projectService = projectService;
    this.permissionValidator = permissionValidator;
  }

  @PreAuthorize(value = "@permissionValidator.canEditProject(#projectId)")
  @PutMapping("/projects/{projectId}")
  public ProjectDTO update(@PathVariable String projectId, @RequestBody ProjectDTO dto) {
    return projectService.update(projectId, dto);
  }

  @GetMapping("/projects/{projectId}/members")
  public List<MemberDTO> members(@PathVariable String projectId) {
    if (!permissionValidator.canViewProject(projectId)) {
      throw new AccessDeniedException("Access is denied");
    }
    return projectService.members(projectId);
  }

  @DeleteMapping("/projects/{projectId}")
  public void delete(@PathVariable String projectId) {
    if (!permissionValidator.canEditProject(projectId)) {
      throw new AccessDeniedException("Access is denied");
    }
    projectService.delete(projectId);
  }

  @GetMapping("/projects/{projectId}/settings")
  public SettingsDTO settings(@PathVariable String projectId) {
    SettingsDTO settings = projectService.settings(projectId);
    return settings;
  }
}
