"use server";

import { resolveUser } from "./resolve-user";
import {
  getProjectPublicUrl as getPublicUrlService,
  updateProjectPublicUrl as updatePublicUrlService,
} from "@onecli/api/services/project-service";
import {
  withAudit,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
} from "@onecli/api/services/audit-service";

export const getPublicUrl = async (): Promise<string> => {
  const { projectId } = await resolveUser();
  return getPublicUrlService(projectId);
};

export const updatePublicUrl = async (publicUrl: string | null) => {
  const { userId, userEmail, projectId } = await resolveUser();

  return withAudit(
    () => updatePublicUrlService(projectId, publicUrl),
    () => ({
      projectId,
      userId,
      userEmail,
      action: AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.PROJECT,
      metadata: { field: "publicUrl", publicUrl },
    }),
  );
};
