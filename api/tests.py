from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from .models import CustomUser, File
from django.core.files.uploadedfile import SimpleUploadedFile

class FileSharingTestCase(APITestCase):

    def setUp(self):
        self.client = APIClient()

        # Create operation user
        self.operation_user = CustomUser.objects.create_user(
            username='operation_user', password='password123', user_type='operation', is_active=True
        )

        # Create client user
        self.client_user = CustomUser.objects.create_user(
            username='client_user', password='password123', user_type='client', is_active=True
        )

        # Login operation user
        response = self.client.post(reverse('token_obtain_pair'), {
            'username': 'operation_user',
            'password': 'password123'
        })
        self.operation_user_token = response.data['access']

        # Login client user
        response = self.client.post(reverse('token_obtain_pair'), {
            'username': 'client_user',
            'password': 'password123'
        })
        self.client_user_token = response.data['access']

    def test_user_signup(self):
        url = reverse('signup')
        data = {
            'username': 'new_user',
            'password': 'newpassword123',
            'email': 'new_user@example.com',
            'user_type': 'client'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)

    def test_email_verification(self):
        user = CustomUser.objects.create_user(
            username='verify_user', password='password123', email='verify@example.com', is_active=False
        )
        token = base64.urlsafe_b64encode(RefreshToken.for_user(user).access_token.encode()).decode()
        url = reverse('verify-email', args=[token])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    def test_user_login(self):
        url = reverse('token_obtain_pair')
        data = {
            'username': 'client_user',
            'password': 'password123'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_file_upload_operation_user(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.operation_user_token)
        url = reverse('upload')
        file = SimpleUploadedFile("file.docx", b"file_content", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        data = {'file': file}
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_file_upload_client_user_denied(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.client_user_token)
        url = reverse('upload')
        file = SimpleUploadedFile("file.docx", b"file_content", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        data = {'file': file}
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_files(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.client_user_token)
        url = reverse('list-files')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_download_file_client_user(self):
    
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.operation_user_token)
        file = SimpleUploadedFile("file.docx", b"file_content", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        upload_response = self.client.post(reverse('upload'), {'file': file}, format='multipart')
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)

    
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.client_user_token)
        file_id = upload_response.data['id']
        url = reverse('download-file', args=[file_id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="file.docx"')

    def test_download_file_operation_user_denied(self):
      
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.operation_user_token)
        file = SimpleUploadedFile("file.docx", b"file_content", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        upload_response = self.client.post(reverse('upload'), {'file': file}, format='multipart')
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)

       
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.operation_user_token)
        file_id = upload_response.data['id']
        url = reverse('download-file', args=[file_id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
