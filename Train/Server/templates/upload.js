const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileNameEl = document.getElementById('fileName');
const removeBtn = document.getElementById('removeBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const loader = document.getElementById('loader');
const waitingText = document.createElement('p');   // Text "Hãy đợi đi..."

waitingText.id = 'waitingText';
waitingText.style.cssText = 'margin-top: 20px; color: #ffaa6b; font-style: italic; display: none;';
loader.parentNode.insertBefore(waitingText, loader.nextSibling);

let selectedFile = null;
let analysisTimeout = null;

// Click & Drag & Drop (giữ nguyên như cũ)
uploadArea.addEventListener('click', (e) => {
  if (e.target.id !== 'removeBtn') fileInput.click();
});

fileInput.addEventListener('change', (e) => handleFiles(e.target.files));

uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.classList.add('dragover'); });
uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
uploadArea.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadArea.classList.remove('dragover');
  handleFiles(e.dataTransfer.files);
});

function handleFiles(files) {
  if (files.length === 0) return;
  const file = files[0];
  if (!file.name.toLowerCase().endsWith('.exe')) {
    alert('Chỉ hỗ trợ file .exe!');
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = file.name;
  fileInfo.classList.add('show');
  analyzeBtn.style.display = 'block';
  uploadArea.style.display = 'none';
}

removeBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  resetUpload();
});

function resetUpload() {
  clearTimeout(analysisTimeout);
  selectedFile = null;
  fileInput.value = '';
  fileInfo.classList.remove('show');
  analyzeBtn.style.display = 'none';
  loader.style.display = 'none';
  waitingText.style.display = 'none';
  uploadArea.style.display = 'flex';
}

analyzeBtn.addEventListener('click', async () => {
  if (!selectedFile) return;

  analyzeBtn.style.display = 'none';
  loader.style.display = 'block';
  waitingText.textContent = "Hãy đợi đi vì file có thể quá nặng...";
  waitingText.style.display = 'block';

  const formData = new FormData();
  formData.append('file', selectedFile);
  formData.append('threshold', '0.65');

  analysisTimeout = setTimeout(() => {
    if (loader.style.display !== 'none') {
      waitingText.textContent = "Đang phân tích sâu... File khá lớn, vui lòng chờ thêm chút nữa nhé!";
    }
  }, 8000);

  try {
    const response = await fetch('http://127.0.0.1:8000/scan', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Lỗi server');
    }

    const result = await response.json();

    if (result.scan_id) {
      localStorage.setItem('lastScanId', result.scan_id);
      console.log("Saved scan_id:", result.scan_id);   // Debug
    } else {
      throw new Error("Server không trả về scan_id");
    }

    window.location.href = 'result.html';

  } catch (error) {
    console.error(error);
    alert('Lỗi khi phân tích:\n' + error.message);
    resetUpload();
  } finally {
    clearTimeout(analysisTimeout);
  }
});