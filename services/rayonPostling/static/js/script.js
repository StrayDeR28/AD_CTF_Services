document.addEventListener('DOMContentLoaded', function () {
    const container = document.querySelector('.card-preview-container');
    const bgImage = document.querySelector('.card-preview-bg');
    const textElement = document.createElement('div');
    const frontTextInput = document.getElementById('front_text');
    const colorInput = document.getElementById('color');
    const fontSelect = document.getElementById('font');
    const posXInput = document.getElementById('pos_x');
    const posYInput = document.getElementById('pos_y');
    const sendBtn = document.getElementById('send-btn');
    const backgroundSelect = document.getElementById('background');

    //      
    textElement.className = 'draggable-text';
    textElement.style.position = 'absolute';
    textElement.textContent = frontTextInput.value || '';
    textElement.style.fontSize = '24px';
    textElement.style.color = colorInput.value;
    textElement.style.fontFamily = fontSelect.value;
    textElement.style.left = posXInput.value + 'px';
    textElement.style.top = posYInput.value + 'px';
    textElement.style.pointerEvents = 'auto'; //  
    textElement.style.cursor = 'move'; //   
    container.appendChild(textElement);

    //  
    frontTextInput.addEventListener('input', function () {
        textElement.textContent = this.value || '';
    });

    colorInput.addEventListener('input', function () {
        textElement.style.color = this.value;
    });

    fontSelect.addEventListener('change', function () {
        textElement.style.fontFamily = this.value;
    });

    posXInput.addEventListener('input', function () {
        textElement.style.left = this.value + 'px';
    });

    posYInput.addEventListener('input', function () {
        textElement.style.top = this.value + 'px';
    });

    backgroundSelect.addEventListener('change', function () {
        bgImage.src = `/static/images/backgrounds/${this.value}`;
    });

    // Drag and drop 
    let isDragging = false;
    let offsetX, offsetY;

    textElement.addEventListener('mousedown', function (e) {
        isDragging = true;
        const rect = textElement.getBoundingClientRect();
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
        textElement.style.cursor = 'grabbing';
        e.preventDefault();
    });

    document.addEventListener('mousemove', function (e) {
        if (!isDragging) return;

        const containerRect = container.getBoundingClientRect();
        let x = e.clientX - containerRect.left - offsetX;
        let y = e.clientY - containerRect.top - offsetY;

        //     
        x = Math.max(0, Math.min(x, containerRect.width - textElement.offsetWidth));
        y = Math.max(0, Math.min(y, containerRect.height - textElement.offsetHeight));

        textElement.style.left = x + 'px';
        textElement.style.top = y + 'px';

        //     
        posXInput.value = Math.round(x);
        posYInput.value = Math.round(y);
    });

    document.addEventListener('mouseup', function () {
        isDragging = false;
        textElement.style.cursor = 'move';
    });

    //   
    sendBtn.addEventListener('click', function () {
        const form = document.getElementById('card-form');
        const fontSizeInput = document.createElement('input');
        fontSizeInput.type = 'hidden';
        fontSizeInput.name = 'font_size';
        fontSizeInput.value = '24';
        form.appendChild(fontSizeInput);
        form.submit();
    });
});