import validators
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .phishing_url_detection import DETECTION
from django.shortcuts import render

logger = logging.getLogger(__name__)





class URLPredictionApiView(APIView):
    def post(self, request):
        try:
            # Get the URL from the request body
            url = request.data.get('url', '').strip()
            if not url:
                return Response(
                    {"success": False, "error": "URL parameter is missing."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Ensure URL starts with http:// or https://
            if not url.startswith(("http://", "https://")):
                url = "http://" + url  # Default to http

            # Validate URL format
            if not validators.url(url):
                return Response(
                    {"success": False, "error": "Invalid URL format."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Instantiate detection class and get the prediction
            detection = DETECTION()
            try:
                prediction = detection.featureExtractions(url)
            except Exception as detection_error:
                logger.error(f"Error during feature extraction: {str(detection_error)}")
                return Response(
                    {"success": False, "error": "Detection system error."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {"success": True, "detection": prediction},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.exception(f"Unhandled error: {str(e)}")
            return Response(
                {"success": False, "error": f"An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
