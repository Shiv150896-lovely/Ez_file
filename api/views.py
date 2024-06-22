from django.shortcuts import render
from django.contrib.auth import authenticate, login
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.core.exceptions import ValidationError, PermissionDenied
from .models import CustomUser, File
from .serializers import UserSerializer, FileSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import HttpResponse
from django.conf import settings
from django.urls import reverse
import os
import base64

class SignUpView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        user = CustomUser.objects.get(username=response.data['username'])
        token = base64.urlsafe_b64encode(RefreshToken.for_user(user).access_token.encode()).decode()
        verification_url = request.build_absolute_uri(reverse('verify-email', args=[token]))
        send_mail(
            'Verify your email',
            f'Click the link to verify your email: {verification_url}',
            settings.EMAIL_HOST_USER,
            [user.email],
        )
        return Response({'message': 'User created successfully. Check your email to verify your account.'}, status=status.HTTP_201_CREATED)

class VerifyEmail(APIView):
    def get(self, request, token):
        try:
            decoded_token = base64.urlsafe_b64decode(token.encode()).decode()
            user = CustomUser.objects.get(auth_token=decoded_token)
            user.is_active = True
            user.save()
            return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

class UploadFileView(generics.CreateAPIView):
    queryset = File.objects.all()
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        if self.request.user.user_type != 'operation':
            raise PermissionDenied("Only operation users can upload files")
        file = self.request.FILES['file']
        if not file.name.endswith(('.pptx', '.docx', '.xlsx')):
            raise ValidationError("Only pptx, docx, and xlsx files are allowed")
        serializer.save(uploader=self.request.user)

class ListFilesView(generics.ListAPIView):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return File.objects.all()

class DownloadFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            file_instance = File.objects.get(pk=pk)
            if request.user.user_type != 'client':
                return Response({'message': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
            file_path = file_instance.file.path
            file_name = os.path.basename(file_path)
            response = HttpResponse(open(file_path, 'rb'), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            return response
        except File.DoesNotExist:
            return Response({'message': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
