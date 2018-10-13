# Copyright (c) 2012-2018 Seafile Ltd.
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.shortcuts import render

from seaserv import seafile_api

from seahub.auth.decorators import login_required
try:
    from seahub.settings import WINDOWS_CLIENT_PUBLIC_DOWNLOAD_URL, \
            WINDOWS_CLIENT_VERSION, APPLE_CLIENT_PUBLIC_DOWNLOAD_URL, \
            APPLE_CLIENT_VERSION, WINDOWS_CLIENT_PUBLIC_DOWNLOAD_URL_EN, \
            WINDOWS_CLIENT_VERSION_EN, APPLE_CLIENT_PUBLIC_DOWNLOAD_URL_EN, \
            APPLE_CLIENT_VERSION_EN

except ImportError:
    WINDOWS_CLIENT_PUBLIC_DOWNLOAD_URL = ''
    WINDOWS_CLIENT_VERSION = ''
    APPLE_CLIENT_PUBLIC_DOWNLOAD_URL = ''
    APPLE_CLIENT_VERSION = ''
    WINDOWS_CLIENT_PUBLIC_DOWNLOAD_URL_EN = ''
    WINDOWS_CLIENT_VERSION_EN = ''
    APPLE_CLIENT_PUBLIC_DOWNLOAD_URL_EN = ''
    APPLE_CLIENT_VERSION_EN = ''

@login_required
def alibaba_client_download_view(request):

    return render(request, 'download.html', {
            'windows_client_public_download_url': WINDOWS_CLIENT_PUBLIC_DOWNLOAD_URL,
            'windows_client_version': WINDOWS_CLIENT_VERSION,
            'apple_client_public_download_url': APPLE_CLIENT_PUBLIC_DOWNLOAD_URL,
            'apple_client_version': APPLE_CLIENT_VERSION,
            'windows_client_public_download_url_en': WINDOWS_CLIENT_PUBLIC_DOWNLOAD_URL_EN,
            'windows_client_version_en': WINDOWS_CLIENT_VERSION_EN,
            'apple_client_public_download_url_en': APPLE_CLIENT_PUBLIC_DOWNLOAD_URL_EN,
            'apple_client_version_en': APPLE_CLIENT_VERSION_EN,
        })

# alibaba api
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from seahub.api2.throttling import UserRateThrottle
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.utils import api_error

from seahub.alibaba.models import AlibabaUserEditFile
from seahub.views import check_folder_permission

logger = logging.getLogger(__name__)

class AlibabaUserEditFileView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):

        # argument check
        repo_id = request.data.get('repo_id', None)
        path = request.data.get('path', None)
        unique_id = request.data.get('unique_id', None)

        if not repo_id:
            error_msg = 'repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not unique_id:
            error_msg = 'unique_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = seafile_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        file_id = seafile_api.get_file_id_by_path(repo_id, path)
        if not file_id:
            error_msg = 'File %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, '/'):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # add user view/edit file start time info
        username = request.user.username
        try:
            AlibabaUserEditFile.objects.add_start_edit_info(username, repo_id,
                    path, unique_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({'success': True})

    def put(self, request):

        unique_id = request.data.get('unique_id', None)
        if not unique_id:
            error_msg = 'unique_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        info = AlibabaUserEditFile.objects.get_edit_info_by_unique_id(unique_id)
        if not info:
            error_msg = 'User view/edit file info %s not found.' % unique_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        repo_id = info.repo_id
        if not check_folder_permission(request, repo_id, '/'):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            AlibabaUserEditFile.objects.complete_end_edit_info(unique_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({'success': True})
