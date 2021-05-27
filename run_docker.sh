#David Archer Demo
# docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#     -v "$PWD/output:/opt/app/toolkit/output" \
#     -it --rm toolkit:latest \
#     task=contrast \
#     contrast_host=eval.contrastsecurity.com \
#     contrast_org_id=a494820a-ae99-4833-980c-e763fcbe1f98 \
#     contrast_api_key=zw426S6zNw6KF4q8CaIqyZkGd5kPOkFI \
#     contrast_auth_token=ZGF2aWQuYXJjaGVyQGNvbnRyYXN0c2VjdXJpdHkuY29tOkFQMjUwQ01WR0xIMEIyVkw= \
#     kenna_appsec_module=true \
#     contrast_include_libs=true \
#     contrast_include_vulns=true \
#     contrast_application_tags=kenna \
#     kenna_api_key=zAm_dn3ZDGqyTRuxcHSY_zkF8Pcwtur3eDsNMiciTTDJwFvCxkC5twNxacj2ECNW \
#     kenna_api_host=api.us.kennasecurity.com \
#     kenna_connector_id=164791

# #Local teamserver
# docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#     -v "$PWD/output:/opt/app/toolkit/output" \
#     -it --rm toolkit:latest \
#     task=contrast \
#     contrast_host=host.docker.internal \
#     contrast_use_https=false \
#     contrast_port=8080 \
#     contrast_org_id=e7995c9b-5eb3-46d0-83e1-1b00ef3f7f5d \
#     contrast_api_key=e6aVRmeXNS4OR9Ep \
#     contrast_auth_token=ZGF2aWRhdXN0aW5hcmNoZXJAaG90bWFpbC5jb206czVjYjUwaTR1c2FyZGtuZTA2YTM3OWVwbHM= \
#     kenna_appsec_module=true \
#     contrast_include_libs=true \
#     contrast_include_vulns=true \
#     kenna_api_key=zAm_dn3ZDGqyTRuxcHSY_zkF8Pcwtur3eDsNMiciTTDJwFvCxkC5twNxacj2ECNW \
#     kenna_api_host=api.us.kennasecurity.com \
#     kenna_connector_id=164791

# David Archer Demo
docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
    -v "$PWD/output:/opt/app/toolkit/output" \
    -it --rm toolkit:latest \
    task=contrast \
    contrast_host=eval.contrastsecurity.com \
    contrast_org_id=a494820a-ae99-4833-980c-e763fcbe1f98 \
    contrast_api_key=zw426S6zNw6KF4q8CaIqyZkGd5kPOkFI \
    contrast_auth_token=ZGF2aWQuYXJjaGVyQGNvbnRyYXN0c2VjdXJpdHkuY29tOkFQMjUwQ01WR0xIMEIyVkw= \
    kenna_appsec_module=false \
    contrast_include_libs=true \
    contrast_include_vulns=true \
    contrast_application_tags=kenna \
    kenna_api_key=LrN4hzSjZLHn8a6uzvyVF7F5cxF1vMa7g__8SPM-RPWtj419EcVdT83z7zvxNMH6 \
    kenna_api_host=api.us.kennasecurity.com \
    kenna_connector_id=164790

#Prashant
# docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#     -v "$PWD/output:/opt/app/toolkit/output" \
#     -it --rm toolkit:latest \
#     task=contrast \
#     contrast_host=apptwo.contrastsecurity.com \
#     contrast_org_id=6fd4271e-2594-423e-b9c4-c355a55a3177 \
#     contrast_api_key=jFVnE4X2iVw0ldUGtCYsIV1oslR0B0HO \
#     contrast_auth_token=c3JfZGlyX2IyYkBvdXRsb29rLmNvbTo5UzdPRkVCOEhBMkpONEE3 \
#     contrast_include_libs=true \
#     contrast_include_vulns=false \
#     kenna_api_key=zAm_dn3ZDGqyTRuxcHSY_zkF8Pcwtur3eDsNMiciTTDJwFvCxkC5twNxacj2ECNW \
#     kenna_api_host=api.us.kennasecurity.com \
#     kenna_connector_id=164762

#Prashant
# docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#     -v "$PWD/output:/opt/app/toolkit/output" \
#     -it --rm toolkit:latest \
#     task=contrast \
#     contrast_host=apptwo.contrastsecurity.com \
#     contrast_org_id=6fd4271e-2594-423e-b9c4-c355a55a3177 \
#     contrast_api_key=jFVnE4X2iVw0ldUGtCYsIV1oslR0B0HO \
#     contrast_auth_token=c3JfZGlyX2IyYkBvdXRsb29rLmNvbTo5UzdPRkVCOEhBMkpONEE3 \
#     kenna_appsec_module=false \
#     contrast_include_libs=true \
#     contrast_include_vulns=true \
#     kenna_api_key=LrN4hzSjZLHn8a6uzvyVF7F5cxF1vMa7g__8SPM-RPWtj419EcVdT83z7zvxNMH6 \
#     kenna_api_host=api.us.kennasecurity.com \
#     kenna_connector_id=164790


# Contrast Sales Engineers
# docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#     -v "$PWD/output:/opt/app/toolkit/output" \
#     -it --rm toolkit:latest \
#     task=contrast \
#     contrast_host=eval.contrastsecurity.com \
#     contrast_org_id=c992a0ef-e965-4f92-a410-e09256a78758 \
#     contrast_api_key=sgHuezwDda34Fu6DJl4u7s2ZSzrn91SB \
#     contrast_auth_token=ZGF2aWQuYXJjaGVyQGNvbnRyYXN0c2VjdXJpdHkuY29tOkFQMjUwQ01WR0xIMEIyVkw= \
#     kenna_api_key=LrN4hzSjZLHn8a6uzvyVF7F5cxF1vMa7g__8SPM-RPWtj419EcVdT83z7zvxNMH6 \
#     kenna_api_host=api.us.kennasecurity.com \
#     kenna_connector_id=164573

# docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#     -it --rm toolkit:latest \
#     task=generator

#  docker run --mount "type=bind,source=$(pwd)/tasks,target=/opt/app/toolkit/tasks" \
#      -it --rm toolkit:latest \
#      task=kenna_api_key_check kenna_api_key=LrN4hzSjZLHn8a6uzvyVF7F5cxF1vMa7g__8SPM-RPWtj419EcVdT83z7zvxNMH6