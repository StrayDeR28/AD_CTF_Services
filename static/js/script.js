// Функция для перетаскивания текста на открытке
document.addEventListener('DOMContentLoaded', function() {
    const cardPreview = document.getElementById('card-preview-container');
    const posXInput = document.getElementById('pos_x');
    const posYInput = document.getElementById('pos_y');
    
    if (cardPreview) {
        let isDragging = false;
        let offsetX, offsetY;
        
        cardPreview.addEventListener('mousedown', function(e) {
            isDragging = true;
            offsetX = e.clientX - cardPreview.getBoundingClientRect().left;
            offsetY = e.clientY - cardPreview.getBoundingClientRect().top;
            e.preventDefault();
        });
        
        document.addEventListener('mousemove', function(e) {
            if (!isDragging) return;
            
            const x = e.clientX - offsetX - cardPreview.parentElement.getBoundingClientRect().left;
            const y = e.clientY - offsetY - cardPreview.parentElement.getBoundingClientRect().top;
            
            // Обновляем позиции
            posXInput.value = Math.max(0, Math.min(x, cardPreview.parentElement.offsetWidth - 50));
            posYInput.value = Math.max(0, Math.min(y, cardPreview.parentElement.offsetHeight - 50));
            
            // Триггерим предпросмотр
            document.getElementById('preview-btn').click();
        });
        
        document.addEventListener('mouseup', function() {
            isDragging = false;
        });
    }
    
    // Инициализация предпросмотра при загрузке
    if (document.getElementById('preview-btn')) {
        document.getElementById('preview-btn').click();
    }
});