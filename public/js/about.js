// Hero gallery auto-rotation (every 2 seconds)
document.addEventListener('DOMContentLoaded', function() {
  var images = document.querySelectorAll('.hero__gallery-img');
  if (images.length > 0) {
    var currentIndex = 0;
    setInterval(function() {
      images[currentIndex].classList.remove('active');
      currentIndex = (currentIndex + 1) % images.length;
      images[currentIndex].classList.add('active');
    }, 2000);
  }
});
